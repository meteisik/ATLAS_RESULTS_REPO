import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SilentLantern {

    static class Container {
        public String containerOne;
    }

    public void runSilentLantern() throws SQLException {
        String data;
        data = System.getenv("SILENT_LANTERN_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SilentLanternSink()).querySilentLantern(dataContainer);
    }
}

class CWE89_P09_V1_SilentLanternSink {
    public void querySilentLantern(CWE89_P09_V1_SilentLantern.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection silentLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLantern");
        Statement silentLanternStatement = null;
        ResultSet silentLanternRows = null;
        try {
            silentLanternStatement = silentLanternConnection.createStatement();
            silentLanternRows = silentLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentLanternRows.getRow());
        } finally {
            if (silentLanternRows != null) {
                silentLanternRows.close();
            }
            if (silentLanternStatement != null) {
                silentLanternStatement.close();
            }
            silentLanternConnection.close();
        }
    }
}
