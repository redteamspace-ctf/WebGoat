/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.io.FilenameUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.FileSystemUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

@Getter
public class ProfileUploadBase implements AssignmentEndpoint {

  private final String webGoatHomeDirectory;

  public ProfileUploadBase(String webGoatHomeDirectory) {
    this.webGoatHomeDirectory = webGoatHomeDirectory;
  }

  protected AttackResult execute(MultipartFile file, String fullName, String username) {
    if (file.isEmpty()) {
      return failed(this).feedback("path-traversal-profile-empty-file").build();
    }
    if (StringUtils.isEmpty(fullName)) {
      return failed(this).feedback("path-traversal-profile-empty-name").build();
    }

    File uploadDirectory = cleanupAndCreateDirectoryForUser(username);

    try {
      // Only a plain file name is accepted: path separators and parent directory references are
      // rejected and the resolved location is verified to be inside the user's upload directory.
      Path uploadRoot = uploadDirectory.toPath().toRealPath();
      Path destination = safeDestination(uploadRoot, fullName);
      if (destination == null) {
        return failed(this)
            .feedback("path-traversal-profile-attempt")
            .feedbackArgs(uploadRoot.resolve("rejected").toString())
            .build();
      }
      var uploadedFile = destination.toFile();
      uploadedFile.createNewFile();
      FileCopyUtils.copy(file.getBytes(), uploadedFile);

      return informationMessage(this)
          .feedback("path-traversal-profile-updated")
          .feedbackArgs(uploadedFile.getAbsoluteFile())
          .build();
    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  /**
   * Resolves {@code fileName} inside {@code uploadRoot}, returning {@code null} when the name
   * contains path elements or would escape the upload directory.
   */
  protected static Path safeDestination(Path uploadRoot, String fileName) {
    if (fileName == null || fileName.isBlank()) {
      return null;
    }
    if (fileName.contains("/") || fileName.contains("\\") || fileName.contains("..")) {
      return null;
    }
    if (fileName.chars().anyMatch(c -> c < 0x20)) {
      return null;
    }
    Path destination = uploadRoot.resolve(fileName).normalize();
    if (!destination.startsWith(uploadRoot) || !uploadRoot.equals(destination.getParent())) {
      return null;
    }
    return destination;
  }

  @SneakyThrows
  protected File cleanupAndCreateDirectoryForUser(String username) {
    var uploadDirectory = new File(this.webGoatHomeDirectory, "/PathTraversal/" + username);
    if (uploadDirectory.exists()) {
      FileSystemUtils.deleteRecursively(uploadDirectory);
    }
    Files.createDirectories(uploadDirectory.toPath());
    return uploadDirectory;
  }

  public ResponseEntity<?> getProfilePicture(@CurrentUsername String username) {
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
        .body(getProfilePictureAsBase64(username));
  }

  protected byte[] getProfilePictureAsBase64(String username) {
    var profilePictureDirectory = new File(this.webGoatHomeDirectory, "/PathTraversal/" + username);
    var profileDirectoryFiles = profilePictureDirectory.listFiles();

    if (profileDirectoryFiles != null && profileDirectoryFiles.length > 0) {
      return Arrays.stream(profileDirectoryFiles)
          .filter(file -> FilenameUtils.isExtension(file.getName(), List.of("jpg", "png")))
          .findFirst()
          .map(
              file -> {
                try (var inputStream = new FileInputStream(profileDirectoryFiles[0])) {
                  return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
                } catch (IOException e) {
                  return defaultImage();
                }
              })
          .orElse(defaultImage());
    } else {
      return defaultImage();
    }
  }

  @SneakyThrows
  protected byte[] defaultImage() {
    var inputStream = getClass().getResourceAsStream("/images/account.png");
    return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
  }
}
