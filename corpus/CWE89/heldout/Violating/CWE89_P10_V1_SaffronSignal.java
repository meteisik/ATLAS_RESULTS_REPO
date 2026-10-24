import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SaffronSignal {

    public static String data;

    public void runSaffronSignal() throws SQLException {
        data = System.getenv("SAFFRON_SIGNAL_FILTER");
        (new CWE89_P10_V1_SaffronSignalSink()).querySaffronSignal();
    }
}

class CWE89_P10_V1_SaffronSignalSink {
    public void querySaffronSignal() throws SQLException {
        String data = CWE89_P10_V1_SaffronSignal.data;
        Connection saffronSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSignal");
        Statement saffronSignalStatement = null;
        ResultSet saffronSignalRows = null;
        try {
            saffronSignalStatement = saffronSignalConnection.createStatement();
            saffronSignalRows = saffronSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronSignalRows.getRow());
        } finally {
            if (saffronSignalRows != null) {
                saffronSignalRows.close();
            }
            if (saffronSignalStatement != null) {
                saffronSignalStatement.close();
            }
            saffronSignalConnection.close();
        }
    }
}
