import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SilentKestrel {

    public static String data;

    public void runSilentKestrel() throws SQLException {
        data = System.getenv("SILENT_KESTREL_FILTER");
        (new CWE89_P10_V1_SilentKestrelSink()).querySilentKestrel();
    }
}

class CWE89_P10_V1_SilentKestrelSink {
    public void querySilentKestrel() throws SQLException {
        String data = CWE89_P10_V1_SilentKestrel.data;
        Connection silentKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentKestrel");
        Statement silentKestrelStatement = null;
        ResultSet silentKestrelRows = null;
        try {
            silentKestrelStatement = silentKestrelConnection.createStatement();
            silentKestrelRows = silentKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentKestrelRows.getRow());
        } finally {
            if (silentKestrelRows != null) {
                silentKestrelRows.close();
            }
            if (silentKestrelStatement != null) {
                silentKestrelStatement.close();
            }
            silentKestrelConnection.close();
        }
    }
}
