import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_ArcticNebulaSafe {

    public void deleteArcticNebulaAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("ARCTIC_NEBULA_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection arcticNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticNebula");
            try {
                PreparedStatement arcticNebulaDelete = arcticNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                arcticNebulaDelete.setString(1, data);
                if (authorized) {
                    arcticNebulaDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                arcticNebulaConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
