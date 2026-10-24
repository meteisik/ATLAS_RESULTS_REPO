import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_AzureGlint {

    public void runAzureGlint() throws SQLException {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_GLINT_FILTER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
