import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_NovaMantis {

    public void deleteNovaMantisAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_MANTIS_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_NovaMantisSink()).applyNovaMantisDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_NovaMantisSink {
    public void applyNovaMantisDeletion(String data, boolean authorized) throws SQLException {
        Connection novaMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaMantis");
        try {
            PreparedStatement novaMantisDelete = novaMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaMantisDelete.setString(1, data);
            novaMantisDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            novaMantisConnection.close();
        }
    }
}
