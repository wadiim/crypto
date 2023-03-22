package org.example;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;
import java.util.Objects;

public class DSAController extends Application {
    public AnchorPane dsaForm;

    @Override
    public void start(Stage stage) throws Exception {
        Scene scene = new Scene(FXMLLoader.load(Objects.requireNonNull(getClass().getResource("/DSAForm.fxml"))));
        stage.setScene(scene);
    }

    public void loadAESForm(ActionEvent actionEvent) throws Exception {
        AESController aesController = new AESController();
        aesController.start((Stage) dsaForm.getScene().getWindow());
    }
}
