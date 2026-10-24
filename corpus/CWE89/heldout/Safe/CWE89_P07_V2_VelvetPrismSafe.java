import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_VelvetPrismSafe {
    private static boolean privateTrue = true;

    public void runVelvetPrism() throws SQLException {
        String data;
        if (privateTrue) {
            data = (new CWE89_P07_V2_VelvetPrismSafeSource()).loadVelvetPrism();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_VelvetPrismSafeSource {
    public String loadVelvetPrism() {
        String data;
        data = "foo";
        return data;
    }
}
