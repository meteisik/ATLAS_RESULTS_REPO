import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_NovaPrismSafe {

    public void deleteNovaPrismAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_PRISM_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_NovaPrismSafeSink()).applyNovaPrismDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_NovaPrismSafeSink {
    public void applyNovaPrismDeletion(String data, boolean authorized) throws SQLException {
        Connection novaPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaPrism");
        try {
            PreparedStatement novaPrismDelete = novaPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaPrismDelete.setString(1, data);
            if (authorized) {
                novaPrismDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            novaPrismConnection.close();
        }
    }
}
