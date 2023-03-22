package org.example;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;
import java.util.Objects;

public class AESController extends Application {
    public AnchorPane aesForm;

    @Override
    public void start(Stage stage) throws Exception {
        Scene scene = new Scene(FXMLLoader.load(Objects.requireNonNull(getClass().getResource("/AESForm.fxml"))));
        stage.setScene(scene);
    }

    public void loadDSAForm(ActionEvent actionEvent) throws Exception {
        DSAController dsaController = new DSAController();
        dsaController.start((Stage) aesForm.getScene().getWindow());
    }
}
