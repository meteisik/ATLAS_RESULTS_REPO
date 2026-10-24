import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AzureGlint {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void runAzureGlint() throws SQLException {
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_GLINT_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AzureGlintSink()).queryAzureGlint();
    }
}

class CWE89_P10_V2_AzureGlintSink {
    public void queryAzureGlint() throws SQLException {
        String data = CWE89_P10_V2_AzureGlint.data;
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
