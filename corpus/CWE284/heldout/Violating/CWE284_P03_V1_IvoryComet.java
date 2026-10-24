import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_IvoryComet {

    private void applyIvoryCometDeletion(String data, boolean authorized) throws SQLException {
        Connection ivoryCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryComet");
        try {
            PreparedStatement ivoryCometDelete = ivoryCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryCometDelete.setString(1, data);
            if (authorized) {
                ivoryCometDelete.executeUpdate();
            }
        } finally {
            ivoryCometConnection.close();
        }
    }

    public void deleteIvoryCometAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_COMET_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyIvoryCometDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
