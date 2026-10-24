import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_ZephyrSignalSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String containerOne;
    }

    public void runZephyrSignal() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_ZephyrSignalSafeSink()).queryZephyrSignal(dataContainer);
    }
}

class CWE89_P09_V2_ZephyrSignalSafeSink {
    public void queryZephyrSignal(CWE89_P09_V2_ZephyrSignalSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection zephyrSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrSignal");
        Statement zephyrSignalStatement = null;
        ResultSet zephyrSignalRows = null;
        try {
            zephyrSignalStatement = zephyrSignalConnection.createStatement();
            zephyrSignalRows = zephyrSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrSignalRows.getRow());
        } finally {
            if (zephyrSignalRows != null) {
                zephyrSignalRows.close();
            }
            if (zephyrSignalStatement != null) {
                zephyrSignalStatement.close();
            }
            zephyrSignalConnection.close();
        }
    }
}
