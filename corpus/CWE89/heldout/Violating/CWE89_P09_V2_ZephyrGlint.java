import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_ZephyrGlint {
    private static int privateFive = 5;

    static class Container {
        public String containerOne;
    }

    public void runZephyrGlint() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ZEPHYR_GLINT_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_ZephyrGlintSink()).queryZephyrGlint(dataContainer);
    }
}

class CWE89_P09_V2_ZephyrGlintSink {
    public void queryZephyrGlint(CWE89_P09_V2_ZephyrGlint.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection zephyrGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrGlint");
        Statement zephyrGlintStatement = null;
        ResultSet zephyrGlintRows = null;
        try {
            zephyrGlintStatement = zephyrGlintConnection.createStatement();
            zephyrGlintRows = zephyrGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrGlintRows.getRow());
        } finally {
            if (zephyrGlintRows != null) {
                zephyrGlintRows.close();
            }
            if (zephyrGlintStatement != null) {
                zephyrGlintStatement.close();
            }
            zephyrGlintConnection.close();
        }
    }
}
