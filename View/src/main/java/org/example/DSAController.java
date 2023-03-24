package org.example;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class DSAController extends Application {
    public AnchorPane dsaForm;
    public TextField privateKeyField;
    public TextField publicKeyField;
    public TextField pField;
    public TextField qField;
    public TextField gField;
    public Button generateButton;
    public Button signButton;
    public Button verifyButton;
    public TextArea messageField;
    public TextArea signatureField;

    private final DSA dsa;

    {
        dsa = new DSA(new SHA1());
    }

    @Override
    public void start(Stage stage) throws Exception {
        Scene scene = new Scene(FXMLLoader.load(Objects.requireNonNull(getClass().getResource("/DSAForm.fxml"))));
        stage.setScene(scene);
    }

    public void loadAESForm(ActionEvent actionEvent) throws Exception {
        AESController aesController = new AESController();
        aesController.start((Stage) dsaForm.getScene().getWindow());
    }

    public void generateKeys(ActionEvent actionEvent) {
        dsa.generateKeys();
        privateKeyField.setText(Convert.convertByteArrayToHexString(dsa.getPrivateKey()));
        publicKeyField.setText(Convert.convertByteArrayToHexString(dsa.getPublicKey()));
        pField.setText(Convert.convertByteArrayToHexString(dsa.getP()));
        qField.setText(Convert.convertByteArrayToHexString(dsa.getQ()));
        gField.setText(Convert.convertByteArrayToHexString(dsa.getG()));
    }

    public void sign(ActionEvent actionEvent) {
        try {
            byte[][] signature = dsa.sign(messageField.getText().getBytes(StandardCharsets.UTF_8));
            signatureField.setText(Convert.convertByteArrayToHexString(signature[0]) + '\n'
                    + Convert.convertByteArrayToHexString(signature[1]));
        } catch (Exception e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void verify(ActionEvent actionEvent) {
        String[] signatureStr = signatureField.getText().split("\n");
        byte[][] signature = new byte[][] {
                Convert.convertHexStringToByteArray(signatureStr[0]),
                Convert.convertHexStringToByteArray(signatureStr[1])
        };
        try {
            String result = (dsa.verify(messageField.getText().getBytes(StandardCharsets.UTF_8), signature))
                    ? "Valid" : "Invalid";
            Dialog.display("Result", result);
        } catch (Exception e) {
            Dialog.display("Error", e.getMessage());
        }
    }
}
