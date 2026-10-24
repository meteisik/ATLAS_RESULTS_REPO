import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_NovaGlint {

    private String novaGlintAccountId;

    private boolean novaGlintAuthorized;

    private void applyNovaGlintDeletion() throws SQLException {
        String data = novaGlintAccountId;
        boolean authorized = novaGlintAuthorized;
        Connection novaGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaGlint");
        try {
            PreparedStatement novaGlintDelete = novaGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaGlintDelete.setString(1, data);
            novaGlintDelete.executeUpdate();
        } finally {
            novaGlintConnection.close();
        }
    }

    public void deleteNovaGlintAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_GLINT_ACCOUNT_ID");
        novaGlintAccountId = data;
        novaGlintAuthorized = isAuthorized(data);
        applyNovaGlintDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
