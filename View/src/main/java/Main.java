import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import java.util.Objects;

public class Main extends Application {
    @Override
    public void start(Stage stage) throws Exception {
        Scene main = new Scene(FXMLLoader.load(Objects.requireNonNull(getClass().getResource("/Main.fxml"))));
        stage.setScene(main);
        stage.setTitle("Crypto");
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}
