import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SilentRaven {

    static class Container {
        public String containerOne;
    }

    public void runSilentRaven() throws SQLException {
        String data;
        data = System.getenv("SILENT_RAVEN_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SilentRavenSink()).querySilentRaven(dataContainer);
    }
}

class CWE89_P09_V1_SilentRavenSink {
    public void querySilentRaven(CWE89_P09_V1_SilentRaven.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection silentRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentRaven");
        Statement silentRavenStatement = null;
        ResultSet silentRavenRows = null;
        try {
            silentRavenStatement = silentRavenConnection.createStatement();
            silentRavenRows = silentRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentRavenRows.getRow());
        } finally {
            if (silentRavenRows != null) {
                silentRavenRows.close();
            }
            if (silentRavenStatement != null) {
                silentRavenStatement.close();
            }
            silentRavenConnection.close();
        }
    }
}
