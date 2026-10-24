import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VividSignal {

    public void runVividSignal() throws SQLException {
        String data;
        data = System.getenv("VIVID_SIGNAL_FILTER");
        CWE89_P12_V1_VividSignalBase baseObject = new CWE89_P12_V1_VividSignalSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VividSignalBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VividSignalSink extends CWE89_P12_V1_VividSignalBase {
    public void action(String data) throws SQLException {
        Connection vividSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSignal");
        Statement vividSignalStatement = null;
        ResultSet vividSignalRows = null;
        try {
            vividSignalStatement = vividSignalConnection.createStatement();
            vividSignalRows = vividSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividSignalRows.getRow());
        } finally {
            if (vividSignalRows != null) {
                vividSignalRows.close();
            }
            if (vividSignalStatement != null) {
                vividSignalStatement.close();
            }
            vividSignalConnection.close();
        }
    }
}
