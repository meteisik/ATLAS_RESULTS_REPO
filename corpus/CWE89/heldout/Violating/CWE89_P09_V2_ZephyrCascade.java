import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_ZephyrCascade {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String containerOne;
    }

    public void runZephyrCascade() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ZEPHYR_CASCADE_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_ZephyrCascadeSink()).queryZephyrCascade(dataContainer);
    }
}

class CWE89_P09_V2_ZephyrCascadeSink {
    public void queryZephyrCascade(CWE89_P09_V2_ZephyrCascade.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection zephyrCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCascade");
        Statement zephyrCascadeStatement = null;
        ResultSet zephyrCascadeRows = null;
        try {
            zephyrCascadeStatement = zephyrCascadeConnection.createStatement();
            zephyrCascadeRows = zephyrCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrCascadeRows.getRow());
        } finally {
            if (zephyrCascadeRows != null) {
                zephyrCascadeRows.close();
            }
            if (zephyrCascadeStatement != null) {
                zephyrCascadeStatement.close();
            }
            zephyrCascadeConnection.close();
        }
    }
}
