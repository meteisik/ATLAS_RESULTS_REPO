import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_ZephyrCipher {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void runZephyrCipher() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("ZEPHYR_CIPHER_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_ZephyrCipherSink()).queryZephyrCipher(dataContainer);
    }
}

class CWE89_P09_V2_ZephyrCipherSink {
    public void queryZephyrCipher(CWE89_P09_V2_ZephyrCipher.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection zephyrCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCipher");
        Statement zephyrCipherStatement = null;
        ResultSet zephyrCipherRows = null;
        try {
            zephyrCipherStatement = zephyrCipherConnection.createStatement();
            zephyrCipherRows = zephyrCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrCipherRows.getRow());
        } finally {
            if (zephyrCipherRows != null) {
                zephyrCipherRows.close();
            }
            if (zephyrCipherStatement != null) {
                zephyrCipherStatement.close();
            }
            zephyrCipherConnection.close();
        }
    }
}
