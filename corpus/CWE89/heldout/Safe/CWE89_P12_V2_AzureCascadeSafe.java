import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureCascadeSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureCascade() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_AzureCascadeSafeBase baseObject = new CWE89_P12_V2_AzureCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureCascadeSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureCascadeSafeSink extends CWE89_P12_V2_AzureCascadeSafeBase {
    public void action(String data) throws SQLException {
        Connection azureCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCascade");
        Statement azureCascadeStatement = null;
        ResultSet azureCascadeRows = null;
        try {
            azureCascadeStatement = azureCascadeConnection.createStatement();
            azureCascadeRows = azureCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureCascadeRows.getRow());
        } finally {
            if (azureCascadeRows != null) {
                azureCascadeRows.close();
            }
            if (azureCascadeStatement != null) {
                azureCascadeStatement.close();
            }
            azureCascadeConnection.close();
        }
    }
}
