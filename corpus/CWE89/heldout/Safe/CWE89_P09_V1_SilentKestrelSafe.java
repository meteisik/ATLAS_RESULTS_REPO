import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SilentKestrelSafe {

    static class Container {
        public String containerOne;
    }

    public void runSilentKestrel() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SilentKestrelSafeSink()).querySilentKestrel(dataContainer);
    }
}

class CWE89_P09_V1_SilentKestrelSafeSink {
    public void querySilentKestrel(CWE89_P09_V1_SilentKestrelSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
