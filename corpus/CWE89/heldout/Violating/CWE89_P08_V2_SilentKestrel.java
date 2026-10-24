import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_SilentKestrel {
    private static boolean privateReturnsTrue() { return true; }

    public void runSilentKestrel() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SILENT_KESTREL_FILTER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_SilentKestrelSink()).querySilentKestrel(dataArray);
    }
}

class CWE89_P08_V2_SilentKestrelSink {
    public void querySilentKestrel(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
