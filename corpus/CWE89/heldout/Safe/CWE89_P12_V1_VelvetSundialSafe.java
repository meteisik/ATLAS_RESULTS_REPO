import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetSundialSafe {

    public void runVelvetSundial() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VelvetSundialSafeBase baseObject = new CWE89_P12_V1_VelvetSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetSundialSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetSundialSafeSink extends CWE89_P12_V1_VelvetSundialSafeBase {
    public void action(String data) throws SQLException {
        Connection velvetSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSundial");
        Statement velvetSundialStatement = null;
        ResultSet velvetSundialRows = null;
        try {
            velvetSundialStatement = velvetSundialConnection.createStatement();
            velvetSundialRows = velvetSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetSundialRows.getRow());
        } finally {
            if (velvetSundialRows != null) {
                velvetSundialRows.close();
            }
            if (velvetSundialStatement != null) {
                velvetSundialStatement.close();
            }
            velvetSundialConnection.close();
        }
    }
}
