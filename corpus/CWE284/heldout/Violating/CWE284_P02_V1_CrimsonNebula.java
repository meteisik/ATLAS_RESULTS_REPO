import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_CrimsonNebula {

    public void deleteCrimsonNebulaAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("CRIMSON_NEBULA_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection crimsonNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonNebula");
            try {
                PreparedStatement crimsonNebulaDelete = crimsonNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                crimsonNebulaDelete.setString(1, data);
                crimsonNebulaDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                crimsonNebulaConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
