import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_AzurePrism {

    public void deleteAzurePrismAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("AZURE_PRISM_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_AzurePrismBase baseObject = new CWE284_P12_V2_AzurePrismRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_AzurePrismBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_AzurePrismRemover extends CWE284_P12_V2_AzurePrismBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection azurePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azurePrism");
        try {
            PreparedStatement azurePrismDelete = azurePrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azurePrismDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                azurePrismDelete.executeUpdate();
            }
        } finally {
            azurePrismConnection.close();
        }
    }
}
