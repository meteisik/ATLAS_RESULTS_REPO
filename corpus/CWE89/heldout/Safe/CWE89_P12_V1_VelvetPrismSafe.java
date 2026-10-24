import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetPrismSafe {

    public void runVelvetPrism() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VelvetPrismSafeBase baseObject = new CWE89_P12_V1_VelvetPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetPrismSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetPrismSafeSink extends CWE89_P12_V1_VelvetPrismSafeBase {
    public void action(String data) throws SQLException {
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
