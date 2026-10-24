import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureGlint() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_AzureGlintSafeBase baseObject = new CWE89_P12_V2_AzureGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureGlintSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureGlintSafeSink extends CWE89_P12_V2_AzureGlintSafeBase {
    public void action(String data) throws SQLException {
        Connection azureGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureGlint");
        Statement azureGlintStatement = null;
        ResultSet azureGlintRows = null;
        try {
            azureGlintStatement = azureGlintConnection.createStatement();
            azureGlintRows = azureGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureGlintRows.getRow());
        } finally {
            if (azureGlintRows != null) {
                azureGlintRows.close();
            }
            if (azureGlintStatement != null) {
                azureGlintStatement.close();
            }
            azureGlintConnection.close();
        }
    }
}
