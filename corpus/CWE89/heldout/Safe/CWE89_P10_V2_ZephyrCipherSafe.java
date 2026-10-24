import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ZephyrCipherSafe {
    private static int privateFive = 5;

    public static String data;

    public void runZephyrCipher() throws SQLException {
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ZephyrCipherSafeSink()).queryZephyrCipher();
    }
}

class CWE89_P10_V2_ZephyrCipherSafeSink {
    public void queryZephyrCipher() throws SQLException {
        String data = CWE89_P10_V2_ZephyrCipherSafe.data;
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
