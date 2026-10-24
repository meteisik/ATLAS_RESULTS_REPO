import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureCipher() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_AzureCipherSafeBase baseObject = new CWE89_P12_V2_AzureCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureCipherSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureCipherSafeSink extends CWE89_P12_V2_AzureCipherSafeBase {
    public void action(String data) throws SQLException {
        Connection azureCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCipher");
        Statement azureCipherStatement = null;
        ResultSet azureCipherRows = null;
        try {
            azureCipherStatement = azureCipherConnection.createStatement();
            azureCipherRows = azureCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureCipherRows.getRow());
        } finally {
            if (azureCipherRows != null) {
                azureCipherRows.close();
            }
            if (azureCipherStatement != null) {
                azureCipherStatement.close();
            }
            azureCipherConnection.close();
        }
    }
}
