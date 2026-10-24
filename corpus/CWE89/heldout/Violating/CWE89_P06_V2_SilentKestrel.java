import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SilentKestrel {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runSilentKestrel() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("SILENT_KESTREL_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SilentKestrelSink()).querySilentKestrel(data);
    }
}

class CWE89_P06_V2_SilentKestrelSink {
    public void querySilentKestrel(String data) throws SQLException {
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
