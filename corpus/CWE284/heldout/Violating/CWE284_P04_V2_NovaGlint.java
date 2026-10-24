import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_NovaGlint {

    private boolean checkNovaGlintAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteNovaGlintAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("NOVA_GLINT_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        boolean authorized = checkNovaGlintAccess(data);
        Connection novaGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaGlint");
        try {
            PreparedStatement novaGlintDelete = novaGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaGlintDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                novaGlintDelete.executeUpdate();
            }
        } finally {
            novaGlintConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
