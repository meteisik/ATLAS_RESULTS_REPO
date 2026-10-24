import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_VividSignalSafe {

    public static String data;

    public void runVividSignal() throws SQLException {
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_VividSignalSafeSink()).queryVividSignal();
    }
}

class CWE89_P10_V2_VividSignalSafeSink {
    public void queryVividSignal() throws SQLException {
        String data = CWE89_P10_V2_VividSignalSafe.data;
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
