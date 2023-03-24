package org.example;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class AESController extends Application {
    @FXML
    public AnchorPane aesForm;
    @FXML
    public TextField keyField;
    @FXML
    public TextArea plainTextField;
    @FXML
    public TextArea encryptedTextField;

    private final AES aes;

    {
        aes = new AES();
    }

    @Override
    public void start(Stage stage) throws Exception {
        Scene scene = new Scene(FXMLLoader.load(Objects.requireNonNull(getClass().getResource("/AESForm.fxml"))));
        scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("/styles.css")).toExternalForm());
        stage.setScene(scene);

        keyField = (TextField) scene.lookup("#keyField");
        keyField.textProperty().addListener((observableValue, s, t1) -> setKey());
    }

    public void loadDSAForm(ActionEvent actionEvent) throws Exception {
        DSAController dsaController = new DSAController();
        dsaController.start((Stage) aesForm.getScene().getWindow());
    }

    public void generateKey(ActionEvent actionEvent) {
        aes.generateKey();
        keyField.setText(Convert.convertByteArrayToHexString(aes.getKey()));
    }

    public void setKey() {
        try {
            aes.setKey(Convert.convertHexStringToByteArray(keyField.getText()));
            keyField.getStyleClass().removeAll("input_error");
        } catch (Exception e) {
            if (! keyField.getStyleClass().contains("input_error")) {
                keyField.getStyleClass().add("input_error");
            }
        }
    }

    public void encrypt(ActionEvent actionEvent) {
        setKey(); // Needed, because listener seems to not always work for some reason.

        try {
            encryptedTextField.setText(Convert.convertByteArrayToHexString(
                    aes.encrypt(plainTextField
                            .getText()
                            .getBytes(StandardCharsets.UTF_8))
            ));
        } catch (Exception e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void decrypt(ActionEvent actionEvent) {
        setKey(); // Needed, because listener seems to not always work for some reason.

        try {
            String decrypted = new String(aes.decrypt(Convert.convertHexStringToByteArray(encryptedTextField.getText())),
                    StandardCharsets.UTF_8);
            plainTextField.setText(decrypted);
        } catch (Exception e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void loadKeyFromFile(ActionEvent actionEvent) {
        FileChooser fc = new FileChooser();
        try (FileInputStream fs = new FileInputStream(fc.showOpenDialog(aesForm.getScene().getWindow()).getPath())) {
            keyField.setText(Convert.convertByteArrayToHexString(fs.readAllBytes()));
        } catch (IOException e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void saveKeyToFile(ActionEvent actionEvent) {
        FileChooser fc = new FileChooser();
        try (FileOutputStream fs = new FileOutputStream(fc.showSaveDialog(aesForm.getScene().getWindow()).getPath())) {
            fs.write(Convert.convertHexStringToByteArray(keyField.getText()));
        } catch (IOException e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void loadMessageFromFile(ActionEvent actionEvent) {
        FileChooser fc = new FileChooser();
        try (FileInputStream fs = new FileInputStream(fc.showOpenDialog(aesForm.getScene().getWindow()).getPath())) {
            plainTextField.setText(new String(fs.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void saveMessageToFile(ActionEvent actionEvent) {
        FileChooser fc = new FileChooser();
        try (FileOutputStream fs = new FileOutputStream(fc.showSaveDialog(aesForm.getScene().getWindow()).getPath())) {
            fs.write(plainTextField.getText().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void loadEncryptedMessageFromFile(ActionEvent actionEvent) {
        FileChooser fc = new FileChooser();
        try (FileInputStream fs = new FileInputStream(fc.showOpenDialog(aesForm.getScene().getWindow()).getPath())) {
            encryptedTextField.setText(Convert.convertByteArrayToHexString(fs.readAllBytes()));
        } catch (IOException e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void saveEncryptedMessageToFile(ActionEvent actionEvent) {
        FileChooser fc = new FileChooser();
        try (FileOutputStream fs = new FileOutputStream(fc.showSaveDialog(aesForm.getScene().getWindow()).getPath())) {
            fs.write(Convert.convertHexStringToByteArray(encryptedTextField.getText()));
        } catch (IOException e) {
            Dialog.display("Error", e.getMessage());
        }
    }
}
