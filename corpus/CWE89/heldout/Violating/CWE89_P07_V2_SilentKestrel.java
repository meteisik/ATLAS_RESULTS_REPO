import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SilentKestrel {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runSilentKestrel() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE89_P07_V2_SilentKestrelSource()).loadSilentKestrel();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_SilentKestrelSource {
    public String loadSilentKestrel() {
        String data;
        data = System.getenv("SILENT_KESTREL_FILTER");
        return data;
    }
}
