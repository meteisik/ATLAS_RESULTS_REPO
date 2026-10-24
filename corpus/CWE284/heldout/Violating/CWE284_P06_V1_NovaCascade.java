import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_NovaCascade {

    public void deleteNovaCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_CASCADE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_NovaCascadeSink()).applyNovaCascadeDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_NovaCascadeSink {
    public void applyNovaCascadeDeletion(String data, boolean authorized) throws SQLException {
        Connection novaCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaCascade");
        try {
            PreparedStatement novaCascadeDelete = novaCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaCascadeDelete.setString(1, data);
            novaCascadeDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            novaCascadeConnection.close();
        }
    }
}
