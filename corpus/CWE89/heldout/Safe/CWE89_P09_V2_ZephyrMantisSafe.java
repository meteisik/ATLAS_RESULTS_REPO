import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_ZephyrMantisSafe {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void runZephyrMantis() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_ZephyrMantisSafeSink()).queryZephyrMantis(dataContainer);
    }
}

class CWE89_P09_V2_ZephyrMantisSafeSink {
    public void queryZephyrMantis(CWE89_P09_V2_ZephyrMantisSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection zephyrMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrMantis");
        Statement zephyrMantisStatement = null;
        ResultSet zephyrMantisRows = null;
        try {
            zephyrMantisStatement = zephyrMantisConnection.createStatement();
            zephyrMantisRows = zephyrMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrMantisRows.getRow());
        } finally {
            if (zephyrMantisRows != null) {
                zephyrMantisRows.close();
            }
            if (zephyrMantisStatement != null) {
                zephyrMantisStatement.close();
            }
            zephyrMantisConnection.close();
        }
    }
}
