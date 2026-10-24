import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_AzureGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteAzureGlintAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AZURE_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_AzureGlintSafeBase baseObject = new CWE284_P12_V2_AzureGlintSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_AzureGlintSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_AzureGlintSafeRemover extends CWE284_P12_V2_AzureGlintSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection azureGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureGlint");
        try {
            PreparedStatement azureGlintDelete = azureGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureGlintDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                azureGlintDelete.executeUpdate();
            }
        } finally {
            azureGlintConnection.close();
        }
    }
}
