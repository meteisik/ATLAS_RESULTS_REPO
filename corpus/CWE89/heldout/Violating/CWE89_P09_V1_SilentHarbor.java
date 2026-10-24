import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SilentHarbor {

    static class Container {
        public String containerOne;
    }

    public void runSilentHarbor() throws SQLException {
        String data;
        data = System.getenv("SILENT_HARBOR_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SilentHarborSink()).querySilentHarbor(dataContainer);
    }
}

class CWE89_P09_V1_SilentHarborSink {
    public void querySilentHarbor(CWE89_P09_V1_SilentHarbor.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection silentHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentHarbor");
        Statement silentHarborStatement = null;
        ResultSet silentHarborRows = null;
        try {
            silentHarborStatement = silentHarborConnection.createStatement();
            silentHarborRows = silentHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentHarborRows.getRow());
        } finally {
            if (silentHarborRows != null) {
                silentHarborRows.close();
            }
            if (silentHarborStatement != null) {
                silentHarborStatement.close();
            }
            silentHarborConnection.close();
        }
    }
}
