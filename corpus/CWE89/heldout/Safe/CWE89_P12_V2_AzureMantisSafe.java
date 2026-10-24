import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureMantis() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_AzureMantisSafeBase baseObject = new CWE89_P12_V2_AzureMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureMantisSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureMantisSafeSink extends CWE89_P12_V2_AzureMantisSafeBase {
    public void action(String data) throws SQLException {
        Connection azureMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureMantis");
        Statement azureMantisStatement = null;
        ResultSet azureMantisRows = null;
        try {
            azureMantisStatement = azureMantisConnection.createStatement();
            azureMantisRows = azureMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureMantisRows.getRow());
        } finally {
            if (azureMantisRows != null) {
                azureMantisRows.close();
            }
            if (azureMantisStatement != null) {
                azureMantisStatement.close();
            }
            azureMantisConnection.close();
        }
    }
}
