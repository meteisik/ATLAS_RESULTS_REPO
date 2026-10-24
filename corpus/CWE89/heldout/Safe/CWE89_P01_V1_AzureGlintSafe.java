import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_AzureGlintSafe {

    public void runAzureGlint() throws SQLException {
        String data;
        data = "foo";
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
