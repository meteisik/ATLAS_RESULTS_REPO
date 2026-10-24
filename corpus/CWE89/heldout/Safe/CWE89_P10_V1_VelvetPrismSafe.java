import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetPrismSafe {

    public static String data;

    public void runVelvetPrism() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_VelvetPrismSafeSink()).queryVelvetPrism();
    }
}

class CWE89_P10_V1_VelvetPrismSafeSink {
    public void queryVelvetPrism() throws SQLException {
        String data = CWE89_P10_V1_VelvetPrismSafe.data;
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
