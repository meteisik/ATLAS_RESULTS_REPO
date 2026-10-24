import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SaffronAurora {

    static class Container {
        public String containerOne;
    }

    public void runSaffronAurora() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_AURORA_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SaffronAuroraSink()).querySaffronAurora(dataContainer);
    }
}

class CWE89_P09_V1_SaffronAuroraSink {
    public void querySaffronAurora(CWE89_P09_V1_SaffronAurora.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection saffronAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronAurora");
        Statement saffronAuroraStatement = null;
        ResultSet saffronAuroraRows = null;
        try {
            saffronAuroraStatement = saffronAuroraConnection.createStatement();
            saffronAuroraRows = saffronAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronAuroraRows.getRow());
        } finally {
            if (saffronAuroraRows != null) {
                saffronAuroraRows.close();
            }
            if (saffronAuroraStatement != null) {
                saffronAuroraStatement.close();
            }
            saffronAuroraConnection.close();
        }
    }
}
