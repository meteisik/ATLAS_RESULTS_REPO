import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AzureGlintSafe {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void runAzureGlint() throws SQLException {
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AzureGlintSafeSink()).queryAzureGlint();
    }
}

class CWE89_P10_V2_AzureGlintSafeSink {
    public void queryAzureGlint() throws SQLException {
        String data = CWE89_P10_V2_AzureGlintSafe.data;
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
