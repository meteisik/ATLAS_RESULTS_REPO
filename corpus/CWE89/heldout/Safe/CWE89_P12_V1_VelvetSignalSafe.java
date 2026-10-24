import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetSignalSafe {

    public void runVelvetSignal() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VelvetSignalSafeBase baseObject = new CWE89_P12_V1_VelvetSignalSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetSignalSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetSignalSafeSink extends CWE89_P12_V1_VelvetSignalSafeBase {
    public void action(String data) throws SQLException {
        Connection velvetSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSignal");
        Statement velvetSignalStatement = null;
        ResultSet velvetSignalRows = null;
        try {
            velvetSignalStatement = velvetSignalConnection.createStatement();
            velvetSignalRows = velvetSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetSignalRows.getRow());
        } finally {
            if (velvetSignalRows != null) {
                velvetSignalRows.close();
            }
            if (velvetSignalStatement != null) {
                velvetSignalStatement.close();
            }
            velvetSignalConnection.close();
        }
    }
}
