import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_VividSignal {

    public static String data;

    public void runVividSignal() throws SQLException {
        if (5 == 5) {
            data = System.getenv("VIVID_SIGNAL_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_VividSignalSink()).queryVividSignal();
    }
}

class CWE89_P10_V2_VividSignalSink {
    public void queryVividSignal() throws SQLException {
        String data = CWE89_P10_V2_VividSignal.data;
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
