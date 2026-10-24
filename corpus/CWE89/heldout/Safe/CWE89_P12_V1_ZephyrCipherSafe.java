import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrCipherSafe {

    public void runZephyrCipher() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ZephyrCipherSafeBase baseObject = new CWE89_P12_V1_ZephyrCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrCipherSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrCipherSafeSink extends CWE89_P12_V1_ZephyrCipherSafeBase {
    public void action(String data) throws SQLException {
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
