import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetPrism {

    public static String data;

    public void runVelvetPrism() throws SQLException {
        data = System.getenv("VELVET_PRISM_FILTER");
        (new CWE89_P10_V1_VelvetPrismSink()).queryVelvetPrism();
    }
}

class CWE89_P10_V1_VelvetPrismSink {
    public void queryVelvetPrism() throws SQLException {
        String data = CWE89_P10_V1_VelvetPrism.data;
        Connection velvetPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetPrism");
        Statement velvetPrismStatement = null;
        ResultSet velvetPrismRows = null;
        try {
            velvetPrismStatement = velvetPrismConnection.createStatement();
            velvetPrismRows = velvetPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetPrismRows.getRow());
        } finally {
            if (velvetPrismRows != null) {
                velvetPrismRows.close();
            }
            if (velvetPrismStatement != null) {
                velvetPrismStatement.close();
            }
            velvetPrismConnection.close();
        }
    }
}
