import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_ZephyrAurora {

    static class Container {
        public String containerOne;
    }

    public void runZephyrAurora() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("ZEPHYR_AURORA_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_ZephyrAuroraSink()).queryZephyrAurora(dataContainer);
    }
}

class CWE89_P09_V2_ZephyrAuroraSink {
    public void queryZephyrAurora(CWE89_P09_V2_ZephyrAurora.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection zephyrAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrAurora");
        Statement zephyrAuroraStatement = null;
        ResultSet zephyrAuroraRows = null;
        try {
            zephyrAuroraStatement = zephyrAuroraConnection.createStatement();
            zephyrAuroraRows = zephyrAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrAuroraRows.getRow());
        } finally {
            if (zephyrAuroraRows != null) {
                zephyrAuroraRows.close();
            }
            if (zephyrAuroraStatement != null) {
                zephyrAuroraStatement.close();
            }
            zephyrAuroraConnection.close();
        }
    }
}
