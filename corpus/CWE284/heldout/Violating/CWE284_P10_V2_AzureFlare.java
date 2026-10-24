import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AzureFlare {
    private static int privateFive = 5;

    public static String data;

    public static boolean authorized;

    public void deleteAzureFlareAccount() throws SQLException {
        if (privateFive == 5) {
            data = System.getenv("AZURE_FLARE_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AzureFlareSink()).applyAzureFlareDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AzureFlareSink {
    public void applyAzureFlareDeletion() throws SQLException {
        String data = CWE284_P10_V2_AzureFlare.data;
        boolean authorized = CWE284_P10_V2_AzureFlare.authorized;
        Connection azureFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureFlare");
        try {
            PreparedStatement azureFlareDelete = azureFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureFlareDelete.setString(1, data);
            azureFlareDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            azureFlareConnection.close();
        }
    }
}
