import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_SilentKestrelSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runSilentKestrel() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_SilentKestrelSafeSink()).querySilentKestrel(dataArray);
    }
}

class CWE89_P08_V2_SilentKestrelSafeSink {
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
